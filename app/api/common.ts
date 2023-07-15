import { NextRequest, NextResponse } from "next/server";

export const OPENAI_URL = "api.openai.com";
const DEFAULT_PROTOCOL = "https";
const DEFAULT_MJ_API_URL = "https://api.zxx.im/";
const PROTOCOL = process.env.PROTOCOL ?? DEFAULT_PROTOCOL;
const BASE_URL = process.env.BASE_URL ?? OPENAI_URL;
const DISABLE_GPT4 = !!process.env.DISABLE_GPT4;
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
      "Cache-Control": "no-store",
      Authorization: authValue,
      ...(process.env.OPENAI_ORG_ID && {
        "OpenAI-Organization": process.env.OPENAI_ORG_ID,
      }),
    },
    method: req.method,
    body: req.body,
    // @ts-ignore
    duplex: "half",
    signal: controller.signal,
  };

  // #1815 try to refuse gpt4 request
  if (DISABLE_GPT4 && req.body) {
    try {
      const clonedBody = await req.text();
      fetchOptions.body = clonedBody;

      const jsonBody = JSON.parse(clonedBody);

      if ((jsonBody?.model ?? "").includes("gpt-4")) {
        return NextResponse.json(
          {
            error: true,
            message: "you are not allowed to use gpt-4 model",
          },
          {
            status: 403,
          },
        );
      }
    } catch (e) {
      console.error("[OpenAI] gpt4 filter", e);
    }
  }

  try {
    const res = await fetch(fetchUrl, fetchOptions);

    // to prevent browser prompt for credentials
    const newHeaders = new Headers(res.headers);
    newHeaders.delete("www-authenticate");
    // to disable nginx buffering
    newHeaders.set("X-Accel-Buffering", "no");

    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: newHeaders,
    });
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
