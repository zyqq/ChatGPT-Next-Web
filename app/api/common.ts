import { NextRequest } from "next/server";

export const OPENAI_URL = "api.openai.com";
const DEFAULT_PROTOCOL = "https";
const DEFAULT_MJ_API_URL = "https://api.zxx.im/";
const PROTOCOL = process.env.PROTOCOL ?? DEFAULT_PROTOCOL;
const BASE_URL = process.env.BASE_URL ?? OPENAI_URL;
const MIDJOURNEY_URL = process.env.MIDJOURNEY_API_URL ?? DEFAULT_MJ_API_URL;
const MIDJOURNEY_IMG_PROXY = process.env.MIDJOURNEY_IMG_PROXY ?? "";

export async function requestOpenai(req: NextRequest) {
  const controller = new AbortController();
  const authValue = req.headers.get("Authorization") ?? "";
  console.log(">>>> [OpenAI Request] ", req);
  const openaiPath = `${req.nextUrl.pathname}${req.nextUrl.search}`.replaceAll(
    "/api/openai/",
    "",
  );

  let baseUrl = BASE_URL;

  if (!baseUrl.startsWith("http")) {
    baseUrl = `${PROTOCOL}://${baseUrl}`;
  }

  console.log("[Proxy] ", openaiPath);
  console.log("[Base Url]", baseUrl);

  if (process.env.OPENAI_ORG_ID) {
    console.log("[Org ID]", process.env.OPENAI_ORG_ID);
  }

  const timeoutId = setTimeout(() => {
    controller.abort();
  }, 10 * 60 * 1000);

  const fetchUrl = `${baseUrl}/${openaiPath}`;
  const fetchOptions: RequestInit = {
    headers: {
      "Content-Type": "application/json",
      Authorization: authValue,
      ...(process.env.OPENAI_ORG_ID && {
        "OpenAI-Organization": process.env.OPENAI_ORG_ID,
      }),
    },
    cache: "no-store",
    method: req.method,
    body: req.body,
    signal: controller.signal,
  };

  try {
    const res = await fetch(fetchUrl, fetchOptions);

    if (res.status === 401) {
      // to prevent browser prompt for credentials
      const newHeaders = new Headers(res.headers);
      newHeaders.delete("www-authenticate");
      return new Response(res.body, {
        status: res.status,
        statusText: res.statusText,
        headers: newHeaders,
      });
    }

    return res;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function requestMidJourney(req: NextRequest) {
  const token = req.headers.get("token") ?? "";

  const reqPath = `${req.nextUrl.pathname}`.replaceAll("/api/midjourney/", "");
  console.log(">>>> [MidJourney Request] ", reqPath);
  let proxyUrl = req.nextUrl.searchParams.get("proxyUrl");
  // 优先界面配置
  proxyUrl = proxyUrl ? proxyUrl : MIDJOURNEY_IMG_PROXY;
  const midJourneyAPIPath =
    `${MIDJOURNEY_URL}` + reqPath + "?proxyUrl=" + proxyUrl;
  console.log(">>> 画图", midJourneyAPIPath);
  if (!token) {
    console.error("[Midjourney Request] invalid api key provided", token);
  }

  return fetch(midJourneyAPIPath, {
    headers: {
      "Content-Type": "application/json",
      token: token,
    },
    cache: "no-store",
    method: req.method,
    body: req.body,
  });
}
