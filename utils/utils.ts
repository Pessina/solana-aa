import * as _ from "lodash";

export function normalizeObject(obj: any): any {
  return _.cloneDeepWith(obj, (value) => {
    if (typeof value === "bigint") return value.toString();
    if (value instanceof Uint8Array) return Array.from(value);
    return undefined; // Let lodash handle other types
  });
}
