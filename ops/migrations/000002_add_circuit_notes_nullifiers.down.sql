ALTER TABLE ONLY circuits DROP COLUMN encryption_key_id;
ALTER TABLE ONLY circuits RENAME COLUMN nullifier_store_id TO store_id;
ALTER TABLE ONLY circuits DROP COLUMN note_store_id;
