import { NextResponse } from "next/server";

const SUPABASE_URL = "https://qyvbzpevinqoqrpzbrcj.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF5dmJ6cGV2aW5xb3FycHpicmNqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2Nzk3MjUsImV4cCI6MjA4OTI1NTcyNX0.HXHGeJeDcengEmXg88l385nyTvVoRhD_8R1-gnwebfw";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, scanId, score, grade } = body;

    if (!email || !email.includes("@")) {
      return new NextResponse("Invalid email", { status: 400 });
    }

    const res = await fetch(`${SUPABASE_URL}/rest/v1/scan_leads`, {
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
