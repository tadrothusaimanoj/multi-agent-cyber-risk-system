import OriginalDashboard from "@/components/OriginalDashboard";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 font-sans">
      <OriginalDashboard />
    </main>
  );
}
