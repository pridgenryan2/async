import { expect, test } from "bun:test";
import { computePiFractionDigits, computePiHashFromDigits, hashDigits } from "../src/pi";

const KNOWN_PI_DIGITS = "14159265358979323846";

test("computePiFractionDigits returns known prefix", () => {
	expect(computePiFractionDigits(0)).toBe("");
	expect(computePiFractionDigits(1)).toBe("1");
	expect(computePiFractionDigits(20)).toBe(KNOWN_PI_DIGITS);
});

test("hashDigits is deterministic", async () => {
	const hash = await hashDigits(4, 1);
	expect(hash).toBe("d4803e17ed18d3d41de0582d5192eca3b1fe8bc09e1361c9f8cc7ecced38b020");
});

test("computePiHashFromDigits uses adjacent digits", async () => {
	const hash0 = await computePiHashFromDigits(0, KNOWN_PI_DIGITS);
	const hash1 = await computePiHashFromDigits(1, KNOWN_PI_DIGITS);
	const hash2 = await computePiHashFromDigits(2, KNOWN_PI_DIGITS);

	expect(hash0).toBe("d4803e17ed18d3d41de0582d5192eca3b1fe8bc09e1361c9f8cc7ecced38b020");
	expect(hash1).toBe("492ab00bbe71db09cc80c473346ab2119a8573638cf8c433e3d91a1a450522fc");
	expect(hash2).toBe("a5886f21fcb5f028633b8e8d7bba1412e9a18c1de1a696da1e0cf0244a9665d4");
});

test("computePiHashFromDigits validates inputs", async () => {
	let error: Error | null = null;
	try {
		await computePiHashFromDigits(-1, KNOWN_PI_DIGITS);
	} catch (err) {
		error = err as Error;
	}
	expect(error?.message).toBe("pi_index_invalid");

	error = null;
	try {
		await computePiHashFromDigits(0, "1");
	} catch (err) {
		error = err as Error;
	}
	expect(error?.message).toBe("pi_digits_short");

	error = null;
	try {
		await computePiHashFromDigits(0, "1x");
	} catch (err) {
		error = err as Error;
	}
	expect(error?.message).toBe("pi_digit_invalid");
});
