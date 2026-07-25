//! Pure mapping from a Discord guild template to a planned Sloga server.
//!
//! Deliberately free of database and HTTP concerns so it can be unit-tested
//! exhaustively. The worker turns an [`ImportPlan`] into real rows.
//!
//! **Slice 0 maps structure only** — server name, categories and channels.
//! Roles, permission overwrites and the `@everyone` mapping are slice 1;
//! emojis and the icon require the optional bot upgrade (slice 2) because
//! templates do not carry them.

use super::template::{channel_type, GuildTemplate, PlaceholderId, TemplateChannel};

/// Sloga name limits (validated at the HTTP routes, which the worker bypasses —
/// so the mapper is where they get enforced).
const NAME_MIN: usize = 1;
const NAME_MAX: usize = 32;
const DESCRIPTION_MAX: usize = 1024;

const FALLBACK_CHANNEL_NAME: &str = "channel";
const FALLBACK_CATEGORY_NAME: &str = "category";
const FALLBACK_SERVER_NAME: &str = "Imported Server";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedChannelKind {
    Text {
        slowmode: Option<u64>,
        announcement: bool,
    },
    Voice {
        max_users: Option<u64>,
    },
    Forum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChannel {
    /// Template placeholder id, used to resolve `parent_id` and the system
    /// channel after real ids are minted.
    pub template_id: PlaceholderId,
    pub name: String,
    pub description: Option<String>,
    pub nsfw: bool,
    pub kind: PlannedChannelKind,
    pub parent: Option<PlaceholderId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCategory {
    pub template_id: PlaceholderId,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    pub server_name: String,
    pub server_description: Option<String>,
    /// Ordered as they should appear.
    pub categories: Vec<PlannedCategory>,
    /// Ordered; `parent` refers to a category's `template_id`.
    pub channels: Vec<PlannedChannel>,
    /// Template id of the channel to mint the welcome invite in, if the guild
    /// nominated a system channel.
    pub system_channel: Option<PlaceholderId>,
    /// Human-readable notes about anything deliberately not imported.
    pub skipped: Vec<String>,
    /// How many source channels the mapper dropped (threads, directory
    /// channels, types Sloga has no equivalent for). Feeds the summary's
    /// skipped count so the number can't contradict the notes beside it.
    pub skipped_channel_count: u32,
}

impl ImportPlan {
    /// Total unit count for progress reporting.
    ///
    /// Channels only: they're the per-item loop the progress bar tracks.
    /// Categories are applied in a single batch write, so counting them here
    /// would make the bar stall at N/(N+M) and then jump to full.
    pub fn total_steps(&self) -> u32 {
        self.channels.len() as u32
    }
}

/// Truncate on a char boundary — Discord allows 100-char names and plenty of
/// non-ASCII; byte slicing would panic mid-codepoint.
fn clamp(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect::<String>()
}

fn clamp_name(raw: Option<&str>, fallback: &str) -> String {
    let cleaned = clamp(raw.unwrap_or(""), NAME_MAX);
    if cleaned.chars().count() < NAME_MIN {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn clamp_description(raw: Option<&str>) -> Option<String> {
    raw.map(|value| clamp(value, DESCRIPTION_MAX))
        .filter(|value| !value.is_empty())
}

/// Discord's `user_limit` uses 0 to mean "unlimited"; Sloga expresses that as
/// absent, so 0 must NOT become `Some(0)` (which would mean "nobody").
fn voice_limit(raw: Option<u64>) -> Option<u64> {
    raw.filter(|limit| *limit > 0)
}

/// Slowmode of 0 means "off" in Discord; keep it absent rather than explicit.
fn slowmode(raw: Option<u64>) -> Option<u64> {
    raw.filter(|value| *value > 0)
}

fn sorted_channels(template: &GuildTemplate) -> Vec<&TemplateChannel> {
    let mut channels: Vec<&TemplateChannel> =
        template.serialized_source_guild.channels.iter().collect();
    // Position is the display order; the placeholder id breaks ties so the
    // result is deterministic (important for tests and for re-imports).
    channels.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id)));
    channels
}

/// Map a fetched template into a plan.
pub fn plan_import(template: &GuildTemplate) -> ImportPlan {
    let guild = &template.serialized_source_guild;
    let mut skipped: Vec<String> = Vec::new();

    let server_name = clamp_name(
        guild
            .name
            .as_deref()
            // Fall back to the template's own name only if the guild name is
            // missing — they are different things.
            .or(Some(template.name.as_str())),
        FALLBACK_SERVER_NAME,
    );

    let ordered = sorted_channels(template);

    // Pass 1: categories, so channel parents can be resolved against them.
    let mut categories: Vec<PlannedCategory> = Vec::new();
    for channel in &ordered {
        if channel.channel_type == channel_type::GUILD_CATEGORY {
            categories.push(PlannedCategory {
                template_id: channel.id.clone(),
                title: clamp_name(channel.name.as_deref(), FALLBACK_CATEGORY_NAME),
            });
        }
    }

    // Pass 2: real channels.
    let mut channels: Vec<PlannedChannel> = Vec::new();
    let mut skipped_threads = 0usize;
    let mut skipped_other = 0usize;

    for channel in &ordered {
        let kind = match channel.channel_type {
            channel_type::GUILD_CATEGORY => continue, // handled above
            channel_type::GUILD_TEXT => PlannedChannelKind::Text {
                slowmode: slowmode(channel.rate_limit_per_user),
                announcement: false,
            },
            channel_type::GUILD_ANNOUNCEMENT => PlannedChannelKind::Text {
                slowmode: slowmode(channel.rate_limit_per_user),
                announcement: true,
            },
            channel_type::GUILD_VOICE => PlannedChannelKind::Voice {
                max_users: voice_limit(channel.user_limit),
            },
            channel_type::GUILD_STAGE_VOICE => {
                // Closest equivalent; stage-specific semantics are lost.
                skipped.push(format!(
                    "\"{}\" was a Stage channel and became a normal voice channel.",
                    clamp_name(channel.name.as_deref(), FALLBACK_CHANNEL_NAME)
                ));
                PlannedChannelKind::Voice {
                    max_users: voice_limit(channel.user_limit),
                }
            }
            channel_type::GUILD_FORUM | channel_type::GUILD_MEDIA => PlannedChannelKind::Forum,
            // Threads live inside channels and are re-created by use, not by
            // import; directory channels have no Sloga equivalent.
            10 | 11 | 12 => {
                skipped_threads += 1;
                continue;
            }
            _ => {
                skipped_other += 1;
                continue;
            }
        };

        // A parent that isn't a real category (or points at a missing entry)
        // degrades to top-level rather than producing a dangling reference.
        let parent = channel.parent_id.as_ref().and_then(|parent_id| {
            categories
                .iter()
                .find(|category| &category.template_id == parent_id)
                .map(|category| category.template_id.clone())
        });

        channels.push(PlannedChannel {
            template_id: channel.id.clone(),
            name: clamp_name(channel.name.as_deref(), FALLBACK_CHANNEL_NAME),
            description: clamp_description(channel.topic.as_deref()),
            nsfw: channel.nsfw,
            kind,
            parent,
        });
    }

    if skipped_threads > 0 {
        skipped.push(format!(
            "{skipped_threads} thread(s) were not imported — threads are created as people use them."
        ));
    }
    if skipped_other > 0 {
        skipped.push(format!(
            "{skipped_other} channel(s) of a type Sloga doesn't have were not imported."
        ));
    }

    // Only keep the system channel if it survived mapping (it may have been a
    // skipped type).
    let system_channel = guild.system_channel_id.as_ref().and_then(|wanted| {
        channels
            .iter()
            .find(|channel| &channel.template_id == wanted)
            .map(|channel| channel.template_id.clone())
    });

    // Categories that ended up with no importable channels are dropped: Sloga
    // renders an empty category as dead weight, and server_edit drops unknown
    // ids anyway.
    let populated: Vec<PlannedCategory> = categories
        .into_iter()
        .filter(|category| {
            channels
                .iter()
                .any(|channel| channel.parent.as_ref() == Some(&category.template_id))
        })
        .collect();

    ImportPlan {
        server_name,
        server_description: clamp_description(guild.description.as_deref()),
        categories: populated,
        channels,
        system_channel,
        skipped,
        skipped_channel_count: (skipped_threads + skipped_other) as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(guild_json: &str) -> GuildTemplate {
        serde_json::from_str(&format!(
            r#"{{"code":"c","name":"Template Name","serialized_source_guild":{guild_json}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn uses_guild_name_not_template_name() {
        let plan = plan_import(&template(r#"{"name":"Real Guild","channels":[]}"#));
        assert_eq!(plan.server_name, "Real Guild");
    }

    #[test]
    fn falls_back_to_template_name_then_placeholder() {
        let plan = plan_import(&template(r#"{"channels":[]}"#));
        assert_eq!(plan.server_name, "Template Name");

        // Neither name present at all.
        let bare: GuildTemplate =
            serde_json::from_str(r#"{"code":"c","name":"","serialized_source_guild":{}}"#).unwrap();
        assert_eq!(plan_import(&bare).server_name, FALLBACK_SERVER_NAME);
    }

    #[test]
    fn maps_channel_types() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"text","position":0,"rate_limit_per_user":10},
                {"id":2,"type":2,"name":"voice","position":1,"user_limit":5},
                {"id":3,"type":5,"name":"news","position":2},
                {"id":4,"type":15,"name":"forum","position":3}
            ]}"#,
        ));

        assert_eq!(plan.channels.len(), 4);
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Text {
                slowmode: Some(10),
                announcement: false
            }
        );
        assert_eq!(
            plan.channels[1].kind,
            PlannedChannelKind::Voice {
                max_users: Some(5)
            }
        );
        assert_eq!(
            plan.channels[2].kind,
            PlannedChannelKind::Text {
                slowmode: None,
                announcement: true
            }
        );
        assert_eq!(plan.channels[3].kind, PlannedChannelKind::Forum);
    }

    #[test]
    fn voice_user_limit_zero_means_unlimited_not_zero() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":2,"name":"v","user_limit":0}]}"#,
        ));
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Voice { max_users: None },
            "user_limit 0 is Discord's 'unlimited' — Some(0) would mean nobody can join"
        );
    }

    #[test]
    fn slowmode_zero_is_absent() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":0,"name":"t","rate_limit_per_user":0}]}"#,
        ));
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Text {
                slowmode: None,
                announcement: false
            }
        );
    }

    #[test]
    fn categories_are_linked_and_ordered_by_position() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":10,"type":0,"name":"second","position":5,"parent_id":1},
                {"id":1,"type":4,"name":"CAT","position":0},
                {"id":11,"type":0,"name":"first","position":1,"parent_id":1}
            ]}"#,
        ));

        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.categories[0].title, "CAT");
        // Ordered by position: "first" (1) before "second" (5)
        assert_eq!(plan.channels[0].name, "first");
        assert_eq!(plan.channels[1].name, "second");
        assert!(plan.channels.iter().all(|c| c.parent.is_some()));
    }

    #[test]
    fn dangling_parent_degrades_to_top_level() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":2,"type":0,"name":"orphan","parent_id":999}]}"#,
        ));
        assert_eq!(plan.channels[0].parent, None);
    }

    #[test]
    fn empty_categories_are_dropped() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":4,"name":"EMPTY","position":0},
                {"id":2,"type":4,"name":"USED","position":1},
                {"id":3,"type":0,"name":"chan","position":2,"parent_id":2}
            ]}"#,
        ));
        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.categories[0].title, "USED");
    }

    #[test]
    fn threads_and_unknown_types_are_skipped_with_notes() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"keep"},
                {"id":2,"type":11,"name":"a thread"},
                {"id":3,"type":14,"name":"directory"}
            ]}"#,
        ));
        assert_eq!(plan.channels.len(), 1);
        assert_eq!(plan.skipped.len(), 2);
        assert!(plan.skipped.iter().any(|note| note.contains("thread")));
    }

    #[test]
    fn long_and_unicode_names_are_clamped_on_char_boundaries() {
        // 40 multi-byte chars — byte slicing here would panic.
        let long_name = "é".repeat(40);
        let plan = plan_import(&template(&format!(
            r#"{{"name":"g","channels":[{{"id":1,"type":0,"name":"{long_name}"}}]}}"#
        )));
        assert_eq!(plan.channels[0].name.chars().count(), NAME_MAX);
    }

    #[test]
    fn blank_names_get_a_fallback() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":0,"name":"   "}]}"#,
        ));
        assert_eq!(plan.channels[0].name, FALLBACK_CHANNEL_NAME);
    }

    #[test]
    fn system_channel_resolves_only_if_it_survived_mapping() {
        let kept = plan_import(&template(
            r#"{"name":"g","system_channel_id":2,"channels":[{"id":2,"type":0,"name":"general"}]}"#,
        ));
        assert_eq!(kept.system_channel, Some(PlaceholderId("2".to_string())));

        // Points at a skipped thread → must not dangle.
        let dropped = plan_import(&template(
            r#"{"name":"g","system_channel_id":2,"channels":[{"id":2,"type":11,"name":"t"}]}"#,
        ));
        assert_eq!(dropped.system_channel, None);
    }

    /// Progress is driven by the per-channel loop, so categories must NOT be
    /// counted — including them made the bar stall at N/(N+M) and then jump
    /// straight to full when the single batch category write landed.
    #[test]
    fn total_steps_counts_channels_only() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":4,"name":"CAT"},
                {"id":2,"type":0,"name":"a","parent_id":1},
                {"id":3,"type":0,"name":"b","parent_id":1}
            ]}"#,
        ));
        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.total_steps(), 2);
    }

    /// The summary's skipped count is rendered next to the prose notes, so the
    /// two must agree: anything the mapper drops has to be countable, not just
    /// described.
    #[test]
    fn skipped_channel_count_matches_what_was_dropped() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"keep"},
                {"id":2,"type":11,"name":"thread"},
                {"id":3,"type":12,"name":"thread two"},
                {"id":4,"type":14,"name":"directory"}
            ]}"#,
        ));
        assert_eq!(plan.channels.len(), 1);
        assert_eq!(plan.skipped_channel_count, 3);
        assert!(!plan.skipped.is_empty());
    }
}
