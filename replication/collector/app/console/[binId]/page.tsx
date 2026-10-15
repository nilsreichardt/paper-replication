import { ConsoleClient } from "@/components/console-client";

export default async function ConsolePage({ params }: { params: Promise<{ binId: string }> }) {
  const { binId } = await params;
  return <ConsoleClient binId={binId} />;
}
