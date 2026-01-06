export interface Contact {
  type: "matrix" | "email" | "calendar";
  title: string;
  description: string;
  url: string;
  linkText: string;
}

export const contacts: Contact[] = [
  {
    type: "matrix",
    title: "Matrix Chat",
    description: "We can have a quick chat on Matrix. I'm usually online during the day.",
    url: "https://matrix.to/#/@bcnelson:matrix.org",
    linkText: "matrix.to",
  },
  {
    type: "email",
    title: "Email",
    description: "You can email me at this address:",
    url: "mailto:bradley@nel.family?subject=bcnelson.dev%20Contact",
    linkText: "bradley@nel.family",
  },
  {
    type: "calendar",
    title: "Schedule a time",
    description: "You can Schedule a time to talk to me.",
    url: "https://calendly.com/d/2fv-6x5-sd9",
    linkText: "Calendly",
  },
];
