# Comments

Use plain English. Name the actor, explain one idea at a time and write for someone outside the conversation. Remove filler and stock AI phrases. Use short sentences instead of semicolons or prose dashes. Avoid constructions such as "not X but Y". Keep punctuation required by syntax, standard terms and exact specification quotes.

Keep a comment only when it adds information that the code cannot show.

## Write one for

- A citation: the spec section and the sentence a rule comes from, so the next reader can check it.
- A constraint the code cannot show: an ordering imposed by another party, a value that has to outlast a round trip, a measured limit.
- A non-obvious decision: why the obvious approach does not work here.

## Do not write one for

- What the code already says. `// reads the cookie` above a function that reads the cookie adds nothing.
- What was removed, rejected or used to happen. State the design that is there. History belongs in the changelog and in `docs/adr/`.
- A restatement of the identifier. A one-line constant does not need 9 lines of prose.
- Reassurance. "This is safe because" without naming the mechanism.

## Length

Match the code. One line of prose per line of code is usually one too many. A paragraph over a three-line function belongs in the package doc, an ADR, or `docs/`.

When a comment grows past a few lines, it is probably documentation. Deployment reasoning belongs in `docs/`, an architectural decision in `docs/adr/`, a user-facing rule in the guide for that command.

## Tests

A test comment explains the requirement being checked. This helps readers find the test when that requirement changes.
