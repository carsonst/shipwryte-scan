import { NextResponse } from "next/server";
import { appendFile } from "fs/promises";
import { join } from "path";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, scanId, score, grade } = body;

    if (!email || !email.includes("@")) {
      return new NextResponse("Invalid email", { status: 400 });
    }

    // For now, append to a simple CSV. Replace with a real DB/CRM later.
    const line = `${new Date().toISOString()},${email},${scanId},${score},${grade}\n`;
    await appendFile(join(process.cwd(), "leads.csv"), line);

    return NextResponse.json({ ok: true });
  } catch (e) {
    console.error("Lead capture error:", e);
    return new NextResponse("Failed", { status: 500 });
  }
}
