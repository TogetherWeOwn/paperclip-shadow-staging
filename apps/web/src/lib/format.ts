/** Format seconds as `m:ss`, or `h:mm:ss` once an hour or more. */
export function formatDuration(totalSeconds: number): string {
	const whole = Math.max(0, Math.floor(totalSeconds));
	const hours = Math.floor(whole / 3600);
	const minutes = Math.floor((whole % 3600) / 60);
	const seconds = whole % 60;
	const mm = hours > 0 ? String(minutes).padStart(2, '0') : String(minutes);
	const ss = String(seconds).padStart(2, '0');
	return hours > 0 ? `${hours}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** Format a byte count with one decimal, e.g. `1.5 KB`. */
export function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let index = Math.min(
		units.length - 1,
		Math.max(0, Math.floor(Math.log(bytes) / Math.log(1024)))
	);
	let rounded = Math.round((bytes / 1024 ** index) * 10) / 10;
	// A value that rounds up to 1024 belongs in the next unit (e.g. 1048575 B -> "1 MB").
	if (rounded >= 1024 && index < units.length - 1) {
		index += 1;
		rounded = Math.round((bytes / 1024 ** index) * 10) / 10;
	}
	return `${Number.isInteger(rounded) && index > 0 ? rounded.toFixed(0) : rounded} ${units[index]}`;
}
