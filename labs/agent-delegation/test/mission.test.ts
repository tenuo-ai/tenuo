import { describe, expect, it } from "vitest";
import { ALICE, BOB } from "../src/mission.ts";
import { FLIGHTS } from "../src/services/flights.ts";

describe("mission flight candidates", () => {
  it("keeps every declared candidate exercisable within its trip constraints", () => {
    for (const trip of [ALICE, BOB]) {
      expect(trip.candidateReservations).toContain(trip.expectedReservation);
      for (const reservation of trip.candidateReservations) {
        const flight = FLIGHTS.find((candidate) => candidate.flightId === reservation);
        expect(flight, `${trip.taskId}: missing candidate ${reservation}`).toBeDefined();
        expect(flight?.origin, `${trip.taskId}: ${reservation} origin`).toBe(trip.origin);
        expect(flight?.destination, `${trip.taskId}: ${reservation} destination`).toBe(trip.destination);
        expect(flight?.price, `${trip.taskId}: ${reservation} price`).toBeLessThanOrEqual(trip.flightBudget);
      }
    }
  });
});
