/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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