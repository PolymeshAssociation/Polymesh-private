// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2020 Polymesh Association

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.

// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// This file is part of Substrate.

// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

//! Some configurable implementations as associated type for the substrate runtime.
//! Auxillary struct/enums

use crate::NegativeImbalance;
use frame_support::traits::{Currency, OnUnbalanced};
use frame_system as system;
use pallet_authorship as authorship;
use pallet_balances as balances;

pub struct Author<R>(sp_std::marker::PhantomData<R>);

impl<R> OnUnbalanced<NegativeImbalance<R>> for Author<R>
where
    R: balances::Config + authorship::Config,
    <R as system::Config>::AccountId: From<polymesh_primitives::AccountId>,
    <R as system::Config>::AccountId: Into<polymesh_primitives::AccountId>,
{
    fn on_nonzero_unbalanced(amount: NegativeImbalance<R>) {
        if let Some(author) = authorship::Pallet::<R>::author() {
            <balances::Pallet<R>>::resolve_creating(&author, amount);
        }
    }
}
