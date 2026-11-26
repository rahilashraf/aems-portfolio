import { type MetadataRoute } from "next";

/** A private administrative application: disallow all crawling. */
export default function robots(): MetadataRoute.Robots {
  return { rules: [{ userAgent: "*", disallow: "/" }] };
}
