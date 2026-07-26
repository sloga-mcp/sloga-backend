//! Soft-reserve loot catalog routes.
//!
//! Static game data (editions → raids → items) backing the soft-res
//! sheet picker; the sheet/reserve routes themselves are channel-scoped
//! and live under /channels. Requires a session like every other route,
//! so responses are `Cache-Control: private` — correct for the browser
//! cache, never storable by a shared cache.

use revolt_database::User;
use revolt_result::Result;
use revolt_rocket_okapi::gen::OpenApiGenerator;
use revolt_rocket_okapi::response::OpenApiResponderInner;
use revolt_rocket_okapi::revolt_okapi::openapi3::Responses;
use revolt_rocket_okapi::OpenApiError;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, Route};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::util::softres_catalog::{self, CatalogEdition, CatalogItem, CatalogRaid};

pub fn routes() -> (Vec<Route>, revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi) {
    openapi_get_routes_spec![catalog, catalog_raid]
}

/// The catalog is static per deployment: let clients keep it for a day.
/// `private` — responses require a session and must never land in a
/// shared cache.
const CACHE_CONTROL: &str = "private, max-age=86400";

/// JSON body with the catalog's Cache-Control header attached.
pub struct CachedJson<T>(pub Json<T>);

impl<'r, T: Serialize> Responder<'r, 'static> for CachedJson<T> {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from(self.0.respond_to(req)?)
            .raw_header("Cache-Control", CACHE_CONTROL)
            .ok()
    }
}

impl<T: JsonSchema + Serialize + Send> OpenApiResponderInner for CachedJson<T> {
    fn responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        <Json<T> as OpenApiResponderInner>::responses(generator)
    }
}

/// One edition with its raid list.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SoftResCatalogEdition {
    #[serde(flatten)]
    pub edition: CatalogEdition,
    /// The edition's raids, in catalog order
    pub raids: Vec<CatalogRaid>,
}

/// Response of `GET /softres/catalog`.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SoftResCatalogResponse {
    /// All editions ordered by `sort`, each with its raids
    pub editions: Vec<SoftResCatalogEdition>,
}

/// Response of `GET /softres/catalog/<raid_id>`.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SoftResRaidItemsResponse {
    /// The raid's catalog metadata
    pub raid: CatalogRaid,
    /// The raid's reservable loot table
    pub items: Vec<CatalogItem>,
}

/// # Fetch Soft-Reserve Catalog
///
/// Editions and their raids for creating soft-reserve sheets. Static
/// game data — not channel-scoped.
#[openapi(tag = "Soft Reserves")]
#[get("/catalog")]
pub async fn catalog(_user: User) -> Result<CachedJson<SoftResCatalogResponse>> {
    let editions = softres_catalog::editions()
        .iter()
        .map(|edition| SoftResCatalogEdition {
            edition: edition.clone(),
            raids: softres_catalog::raids_of_edition(&edition.id)
                .cloned()
                .collect(),
        })
        .collect();

    Ok(CachedJson(Json(SoftResCatalogResponse { editions })))
}

/// # Fetch Raid Loot Table
///
/// The reservable item list of one raid from the static catalog.
#[openapi(tag = "Soft Reserves")]
#[get("/catalog/<raid_id>")]
pub async fn catalog_raid(
    _user: User,
    raid_id: String,
) -> Result<CachedJson<SoftResRaidItemsResponse>> {
    let items = softres_catalog::raid_items(&raid_id)?;
    let raid = softres_catalog::raid(&raid_id)
        .expect("raid_items validated existence")
        .clone();

    Ok(CachedJson(Json(SoftResRaidItemsResponse {
        raid,
        items: items.to_vec(),
    })))
}
