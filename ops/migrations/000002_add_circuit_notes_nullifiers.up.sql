ALTER TABLE ONLY circuits ADD COLUMN encryption_key_id uuid;
ALTER TABLE ONLY circuits RENAME COLUMN store_id TO nullifier_store_id;
ALTER TABLE ONLY circuits ADD COLUMN note_store_id uuid;
