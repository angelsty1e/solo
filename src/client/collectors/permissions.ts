import type { PermissionsSnapshot } from '../../shared/types.js';

const NAMES: PermissionName[] = [
  'geolocation',
  'notifications',
  'camera' as PermissionName,
  'microphone' as PermissionName,
  'midi' as PermissionName,
  'clipboard-read' as PermissionName,
  'clipboard-write' as PermissionName,
  'persistent-storage' as PermissionName,
  'background-sync' as PermissionName,
  'accelerometer' as PermissionName,
  'gyroscope' as PermissionName,
  'magnetometer' as PermissionName,
];

export async function collectPermissions(): Promise<PermissionsSnapshot> {
  const states: Record<string, string> = {};
  if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
    return { states };
  }
  for (const name of NAMES) {
    try {
      const status = await navigator.permissions.query({ name });
      states[name] = status.state;
    } catch {
      states[name] = 'unsupported';
    }
  }
  return { states };
}
