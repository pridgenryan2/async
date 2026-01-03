import { computePiFractionDigits, computePiHashFromDigits } from "@queue/core";

export { computePiFractionDigits, computePiHashFromDigits };

export const MAX_PI_INDEX = 10_000;

export async function computePiHash(index: number): Promise<string> {
	if (!Number.isInteger(index) || index < 0) {
		throw new Error("pi_index_invalid");
	}
	if (index > MAX_PI_INDEX) {
		throw new Error("pi_index_limit");
	}
	const digits = computePiFractionDigits(index + 2);
	return computePiHashFromDigits(index, digits);
}
