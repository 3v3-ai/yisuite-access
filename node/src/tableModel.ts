// An AppModel described by plain data (twin of python table_model.TableModel).
import { AppModel, PLATFORM } from './decision';

export interface TableModelData {
  plans: Record<string, string[]>;
  roles: Record<string, string[]>;
  owners: [string, string][];
  default_roles: Record<string, string>;
  read_markers: string[];
  export_markers: string[];
}

export class TableModel implements AppModel {
  constructor(private d: TableModelData) {}

  bundleForKey(key: string): string | null {
    let best: string | null = null;
    let bestLen = -1;
    for (const [prefix, bundle] of this.d.owners) {
      if (key === prefix || (key.startsWith(prefix) && ['.', '-'].includes(key.charAt(prefix.length)))) {
        if (prefix.length > bestLen) { best = bundle; bestLen = prefix.length; }
      }
    }
    return best;
  }
  planBundles(planKey: string) { return this.d.plans[planKey] ?? null; }
  roleKeys(role: string) { return this.d.roles[role] ?? []; }
  defaultRole(orgRole: string | null | undefined) { return this.d.default_roles[orgRole ?? ''] ?? null; }
  isWrite(method: string, path: string) {
    return !['GET', 'HEAD', 'OPTIONS'].includes(method) && !this.d.read_markers.some(m => path.includes(m));
  }
  isExport(path: string) { return this.d.export_markers.some(m => path.includes(m)); }
}

export { PLATFORM };
