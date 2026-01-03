const TEXT_ENCODER = new TextEncoder();
const LOG10_16 = Math.log10(16);
const DEFAULT_EXTRA_DIGITS = 8;

function readDigit(digits: string, index: number): number {
	const code = digits.charCodeAt(index);
	if (!Number.isFinite(code)) {
		throw new Error("pi_digit_missing");
	}
	const value = code - 48;
	if (value < 0 || value > 9) {
		throw new Error("pi_digit_invalid");
	}
	return value;
}

export function bbpPiScaled(precision: number): bigint {
	const scale = 10n ** BigInt(precision);
	let sum = 0n;
	let power16 = 1n;
	const terms = Math.ceil((precision + 1) / LOG10_16) + 1;

	for (let k = 0; k < terms; k += 1) {
		const kBig = BigInt(k);
		const eightK = 8n * kBig;
		const scaleDiv = scale / power16;
		if (scaleDiv === 0n) {
			break;
		}
		let term = (scaleDiv * 4n) / (eightK + 1n);
		term -= (scaleDiv * 2n) / (eightK + 4n);
		term -= scaleDiv / (eightK + 5n);
		term -= scaleDiv / (eightK + 6n);
		sum += term;
		power16 *= 16n;
	}
	return sum;
}

export function computePiFractionDigits(count: number, extraDigits = DEFAULT_EXTRA_DIGITS): string {
	if (count <= 0) {
		return "";
	}
	const precision = count + extraDigits;
	const scaled = bbpPiScaled(precision);
	let digits = scaled.toString();
	if (digits.length <= precision) {
		digits = "0".repeat(precision + 1 - digits.length) + digits;
	}
	const fractional = digits.slice(-precision);
	return fractional.slice(0, count);
}

export async function hashDigits(nextDigit: number, currentDigit: number): Promise<string> {
	const data = TEXT_ENCODER.encode(`${nextDigit}:${currentDigit}`);
	const digest = await crypto.subtle.digest("SHA-256", data);
	let hex = "";
	for (const byte of new Uint8Array(digest)) {
		hex += byte.toString(16).padStart(2, "0");
	}
	return hex;
}

export async function computePiHashFromDigits(index: number, digits: string): Promise<string> {
	if (!Number.isInteger(index) || index < 0) {
		throw new Error("pi_index_invalid");
	}
	if (digits.length < index + 2) {
		throw new Error("pi_digits_short");
	}
	const current = readDigit(digits, index);
	const next = readDigit(digits, index + 1);
	return hashDigits(next, current);
}
