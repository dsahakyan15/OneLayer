-- initialize_registry starts at version 0; the protocol encodes an unsigned
-- registry version. Preserve that value when projecting a workflow anchor for
-- certificate lookup instead of rejecting a valid finalized first publication.
ALTER TABLE demo_anchor DROP CONSTRAINT demo_anchor_registry_version_check;
ALTER TABLE demo_anchor ADD CONSTRAINT demo_anchor_registry_version_check
  CHECK (registry_version >= 0);
