export type JsonQueryValue = string | string[];

export type RequestLog = {
  id: string;
  binId: string;
  method: string;
  path: string;
  query: Record<string, JsonQueryValue>;
  headers: Record<string, string>;
  contentType: string | null;
  bodyText: string | null;
  bodyBase64: string | null;
  truncated: boolean;
  receivedAt: string;
  expiresAt: string;
};

export type RequestInsert = Omit<RequestLog, "id">;

export type PaginatedResult = {
  binId: string;
  items: RequestLog[];
  nextBefore: string | null;
};
