/** Activities. Five in Cancún, one in Seattle. */
export interface Activity {
  readonly activityId: string;
  readonly name: string;
  readonly city: string;
  readonly price: number;
}

export const ACTIVITIES: readonly Activity[] = [
  { activityId: "ACT-1", name: "Cenote tour", city: "Cancún", price: 65 },
  { activityId: "ACT-2", name: "Reef snorkel", city: "Cancún", price: 80 },
  { activityId: "ACT-3", name: "Chichén Itzá day trip", city: "Cancún", price: 180 },
  { activityId: "ACT-4", name: "Sunset catamaran", city: "Cancún", price: 120 },
  { activityId: "ACT-5", name: "Street food walk", city: "Cancún", price: 35 },
  { activityId: "ACT-6", name: "Underground tour", city: "Seattle", price: 40 },
];
