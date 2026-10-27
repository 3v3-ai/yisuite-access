// The one rule for "does this held key grant that wanted key" (twin of python/yisuite_access/keys.py;
// both run contracts/key_cover_cases.json). A held key grants the wanted key when it is the same key,
// an ancestor at a '.' or '-' boundary, or the wanted key's registered parent.
const BOUNDARIES = ['.', '-'];

export function covers(held: Iterable<string>, wanted: string, parent: string | null = null): boolean {
  for (const h of held) {
    if (h === wanted) return true;
    if (wanted.startsWith(h) && BOUNDARIES.includes(wanted.charAt(h.length))) return true;
    if (parent !== null && h === parent) return true;
  }
  return false;
}
