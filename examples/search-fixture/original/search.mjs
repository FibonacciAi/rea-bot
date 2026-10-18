// Owned synthetic fixture, provided under this package's MIT license.
export function search(items, query) {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return [];
  return items.filter(item => item.toLowerCase().includes(needle));
}
