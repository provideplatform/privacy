ALTER TABLE ONLY circuits RENAME TO provers;

CREATE INDEX idx_circuits_application_id ON public.circuits USING btree (application_id);

ALTER INDEX idx_circuits_organization_id RENAME TO idx_provers_organization_id;
ALTER INDEX idx_circuits_user_id RENAME TO idx_provers_user_id;
ALTER INDEX idx_circuits_provider RENAME TO idx_provers_provider;
ALTER INDEX idx_circuits_proving_scheme RENAME TO idx_provers_proving_scheme;
ALTER INDEX idx_circuits_curve RENAME TO idx_provers_curve;
ALTER INDEX idx_circuits_status RENAME TO idx_provers_status;
