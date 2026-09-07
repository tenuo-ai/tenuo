/** Hotels. Six in Cancún so the budget has teeth, one in Tulum for the incident, one in Seattle for Bob. */
export interface Hotel {
  readonly hotelId: string;
  readonly name: string;
  readonly city: string;
  readonly nightlyRate: number;
}

export const HOTELS: readonly Hotel[] = [
  { hotelId: "HTL-CUN-1", name: "Playa Norte Inn", city: "Cancún", nightlyRate: 95 },
  { hotelId: "HTL-CUN-2", name: "Casa Coral", city: "Cancún", nightlyRate: 140 },
  { hotelId: "HTL-CUN-3", name: "Hotel Zona Azul", city: "Cancún", nightlyRate: 185 },
  { hotelId: "HTL-CUN-4", name: "Reef Grand", city: "Cancún", nightlyRate: 240 },
  { hotelId: "HTL-CUN-5", name: "Laguna Palace", city: "Cancún", nightlyRate: 310 },
  { hotelId: "HTL-CUN-6", name: "Isla Suites", city: "Cancún", nightlyRate: 340 },
  { hotelId: "HTL-TUL-1", name: "Tulum Beach House", city: "Tulum", nightlyRate: 220 },
  { hotelId: "HTL-SEA-1", name: "Pike Place Lodge", city: "Seattle", nightlyRate: 190 },
];

/** The hotel the recorded run books for Alice. */
export const APPROVED_HOTEL = "HTL-CUN-2";
