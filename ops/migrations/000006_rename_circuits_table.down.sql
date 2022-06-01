/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

ALTER TABLE ONLY provers RENAME TO circuits;

ALTER INDEX idx_provers_application_id RENAME TO idx_circuits_application_id;
ALTER INDEX idx_provers_organization_id RENAME TO idx_circuits_organization_id;
ALTER INDEX idx_provers_user_id RENAME TO idx_circuits_user_id;
ALTER INDEX idx_provers_provider RENAME TO idx_circuits_provider;
ALTER INDEX idx_provers_proving_scheme RENAME TO idx_circuits_proving_scheme;
ALTER INDEX idx_provers_curve RENAME TO idx_circuits_curve;
ALTER INDEX idx_provers_status RENAME TO idx_circuits_status;
