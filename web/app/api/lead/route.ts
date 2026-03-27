import { NextResponse } from "next/server";

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, scanId, score, grade } = body;

    if (!email || !email.includes("@")) {
      return new NextResponse("Invalid email", { status: 400 });
    }

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      console.error("Supabase not configured");
      return new NextResponse("Lead capture unavailable", { status: 500 });
    }

    const endpoint = `${SUPABASE_URL}/rest/v1/scan_leads`;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        email,
        scan_id: scanId,
        score,
        grade,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error("Supabase insert error:", err);
      return new NextResponse("Failed to save lead", { status: 500 });
    }

    return NextResponse.json({ ok: true });
  } catch (e) {
    console.error("Lead capture error:", e);
    return new NextResponse("Failed", { status: 500 });
  }
}
