describe("cifra http exchange", () => {
	it("visualizes a completed exchange", () => {
		cy.visit("/");

		cy.get("[data-testid=exchange-status]").should(
			"contain.text",
			"Complete",
		);

		cy.get("[data-testid=initiator-log] li")
			.should("have.length.at.least", 3)
			.and("contain.text", "Hello")
			.and("contain.text", "Opened");

		cy.get("[data-testid=responder-log] li")
			.should("have.length.at.least", 2)
			.and("contain.text", "Reply")
			.and("contain.text", "Encrypt");
	});
});
