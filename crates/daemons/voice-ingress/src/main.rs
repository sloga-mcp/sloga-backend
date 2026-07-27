use std::env;

use revolt_database::DatabaseInfo;
use revolt_database::{voice::VoiceClient, AMQP};
use revolt_result::Result;
use rocket::{build, routes, Config};
use std::net::Ipv4Addr;

mod api;
mod guard;
mod reconcile;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    revolt_config::configure!(voice_ingress);

    let amqp = AMQP::new_auto().await;

    let database = DatabaseInfo::Auto.connect().await.unwrap();
    let voice_client = VoiceClient::from_revolt_config().await;

    // Webhooks alone can't keep voice state truthful — a LiveKit restart
    // never delivers the participant_left/room_finished events for the
    // rooms it lost, stranding "in a call" state forever. The sweep
    // replays them. See reconcile.rs.
    rocket::tokio::spawn(reconcile::run(database.clone(), amqp.clone()));

    let _rocket = build()
        .manage(database)
        .manage(voice_client)
        .manage(amqp)
        .mount("/", routes![api::ingress])
        .configure(Config {
            port: 8500,
            address: Ipv4Addr::new(0, 0, 0, 0).into(),
            ..Default::default()
        })
        .ignite()
        .await?
        .launch()
        .await?;

    Ok(())
}
