/** Traveler profiles. Obviously synthetic; do not reuse as test data anywhere real. */
export interface TravelerProfile {
  readonly name: string;
  readonly email: string;
  readonly phone: string;
  readonly passportNumber: string;
  readonly dateOfBirth: string;
  readonly frequentFlyerNumber: string;
}

/** Obviously synthetic. Do not reuse as test data anywhere real. */
export const PROFILES: Readonly<Record<string, TravelerProfile>> = {
  "Alice Chen": {
    name: "Alice Chen",
    email: "alice.chen@example.test",
    phone: "+1-555-0100",
    passportNumber: "SYNTH-P-000001",
    dateOfBirth: "2001-04-12",
    frequentFlyerNumber: "FF-SYNTH-1",
  },
  "Bob Reyes": {
    name: "Bob Reyes",
    email: "bob.reyes@example.test",
    phone: "+1-555-0101",
    passportNumber: "SYNTH-P-000002",
    dateOfBirth: "2000-09-30",
    frequentFlyerNumber: "FF-SYNTH-2",
  },
};

export const SENSITIVE_FIELDS = ["passportNumber", "dateOfBirth"] as const;
