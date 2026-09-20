import {join, resolve} from 'node:path';

export const repoRootDirPath = resolve(import.meta.dirname, '..');
export const notCommittedDirPath = join(repoRootDirPath, '.not-committed');
