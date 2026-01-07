export interface Project {
  name: string;
  description: string;
  tags: string[];
  category: "infra" | "backend" | "fullstack" | "tool";
  status: "active" | "maintained" | "archived";
  links: {
    source?: string;
    demo?: string;
    docs?: string;
  };
}

export const projects: Project[] = [
  // Placeholder projects - replace with your actual projects
  {
    name: "bcnelson.dev",
    description:
      "This portfolio site built with Astro, Vue, and Tailwind. Deployed on Cloudflare Workers with Pulumi IaC.",
    tags: ["Astro", "Vue", "Tailwind", "Cloudflare", "Pulumi"],
    category: "fullstack",
    status: "active",
    links: {
      source: "https://github.com/bcnelson/bcnelsonDev",
      demo: "https://bcnelson.dev",
    },
  },
  // Add more projects here
];

export const categories = [
  { id: "all", label: "All" },
  { id: "infra", label: "Infra" },
  { id: "backend", label: "Backend" },
  { id: "fullstack", label: "Full-Stack" },
  { id: "tool", label: "Tools" },
];
