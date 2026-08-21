import { registerRule } from "../runner";
import { superuserRoles } from "./superuser-roles";
import { publicSchemaGrants } from "./public-schema-grants";
import { missingRls } from "./missing-rls";
import { sslNotEnforced } from "./ssl-not-enforced";
import { outdatedVersion } from "./outdated-version";
import { loggingDisabled } from "./logging-disabled";
import { plaintextSecretColumns } from "./plaintext-secret-columns";
import { schemaDiff } from "./schema-diff";

let registered = false;

export function registerAllRules(): void {
  if (registered) return;
  registerRule(superuserRoles);
  registerRule(publicSchemaGrants);
  registerRule(missingRls);
  registerRule(sslNotEnforced);
  registerRule(outdatedVersion);
  registerRule(loggingDisabled);
  registerRule(plaintextSecretColumns);
  registerRule(schemaDiff);
  registered = true;
}
