ALTER TABLE ONLY provers RENAME TO circuits;

ALTER INDEX idx_provers_organization_id RENAME TO idx_circuits_organization_id;
ALTER INDEX idx_provers_user_id RENAME TO idx_circuits_user_id;
ALTER INDEX idx_provers_provider RENAME TO idx_circuits_provider;
ALTER INDEX idx_provers_proving_scheme RENAME TO idx_circuits_proving_scheme;
ALTER INDEX idx_provers_curve RENAME TO idx_circuits_curve;
ALTER INDEX idx_provers_status RENAME TO idx_circuits_status;
