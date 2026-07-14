pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{PartialSoundboardSound, SoundboardSound};

#[async_trait]
pub trait AbstractSoundboard: Sync + Send {
    async fn insert_soundboard_sound(&self, sound: &SoundboardSound) -> Result<()>;
    async fn fetch_soundboard_sound(&self, id: &str) -> Result<SoundboardSound>;
    async fn fetch_soundboard_sounds_by_server_id(
        &self,
        server_id: &str,
    ) -> Result<Vec<SoundboardSound>>;
    async fn fetch_soundboard_sounds_by_server_ids(
        &self,
        server_ids: &[String],
    ) -> Result<Vec<SoundboardSound>>;
    async fn update_soundboard_sound(
        &self,
        sound_id: &str,
        partial: &PartialSoundboardSound,
    ) -> Result<()>;
    async fn delete_soundboard_sound(&self, sound_id: &str) -> Result<()>;
}
