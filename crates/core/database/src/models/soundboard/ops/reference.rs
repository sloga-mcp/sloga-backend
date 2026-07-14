use revolt_result::Result;

use crate::{PartialSoundboardSound, ReferenceDb, SoundboardSound};

use super::AbstractSoundboard;

#[async_trait]
impl AbstractSoundboard for ReferenceDb {
    async fn insert_soundboard_sound(&self, sound: &SoundboardSound) -> Result<()> {
        let mut sounds = self.soundboard_sounds.lock().await;
        if sounds.contains_key(&sound.id) {
            Err(create_database_error!("insert", "soundboard_sound"))
        } else {
            sounds.insert(sound.id.clone(), sound.clone());
            Ok(())
        }
    }

    async fn fetch_soundboard_sound(&self, id: &str) -> Result<SoundboardSound> {
        let sounds = self.soundboard_sounds.lock().await;
        sounds
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_soundboard_sounds_by_server_id(
        &self,
        server_id: &str,
    ) -> Result<Vec<SoundboardSound>> {
        let sounds = self.soundboard_sounds.lock().await;
        Ok(sounds
            .values()
            .filter(|s| s.server_id == server_id)
            .cloned()
            .collect())
    }

    async fn fetch_soundboard_sounds_by_server_ids(
        &self,
        server_ids: &[String],
    ) -> Result<Vec<SoundboardSound>> {
        let sounds = self.soundboard_sounds.lock().await;
        Ok(sounds
            .values()
            .filter(|s| server_ids.contains(&s.server_id))
            .cloned()
            .collect())
    }

    async fn update_soundboard_sound(
        &self,
        sound_id: &str,
        partial: &PartialSoundboardSound,
    ) -> Result<()> {
        let mut sounds = self.soundboard_sounds.lock().await;
        if let Some(sound) = sounds.get_mut(sound_id) {
            if let Some(name) = partial.name.clone() {
                sound.name = name;
            }
            if let Some(emoji) = partial.emoji.clone() {
                sound.emoji = Some(emoji);
            }
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_soundboard_sound(&self, sound_id: &str) -> Result<()> {
        let mut sounds = self.soundboard_sounds.lock().await;
        if sounds.remove(sound_id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }
}
