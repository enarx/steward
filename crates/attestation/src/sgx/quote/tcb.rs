// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::DateTime;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbRoot {
    pub tcb_info: TcbInfo,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u8,
    pub issue_date: DateTime<chrono::Local>,
    pub next_update: DateTime<chrono::Local>,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u8,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: DateTime<chrono::Local>,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    pub sgxtcbcomponents: Vec<Sgxtcbcomponent>,
    pub pcesvn: u8,
}

#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sgxtcbcomponent {
    pub svn: u8,
}
