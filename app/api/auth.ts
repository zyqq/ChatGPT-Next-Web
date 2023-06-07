import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX } from "../constant";
import { OPENAI_URL } from "./common";

const serverConfig = getServerSideConfig();
function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isOpenAiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isOpenAiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isOpenAiKey ? token : "",
  };
}
function parseMjKey(stringToken: string) {
  const token = stringToken.trim();
  const isMjKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    midJourneyAccessCode: isMjKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    midJourneyKey: isMjKey ? token : "",
  };
}

export function auth(req: NextRequest) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  const { accessCode, apiKey: token } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());

  if (serverConfig.needCode && !serverConfig.codes.has(hashedCode) && !token) {
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code",
    };
  }

  // if user does not provide an api key, inject system api key
  if (!token) {
    const apiKey = serverConfig.apiKey;
    if (apiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${apiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  return {
    error: false,
  };
}

export function authMj(req: NextRequest) {
  const authToken = req.headers.get("token") ?? "";

  // check if it is openai api key or user token
  const { midJourneyAccessCode, midJourneyKey } = parseMjKey(authToken);

  const hashedCode = md5.hash(midJourneyAccessCode ?? "").trim();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", midJourneyAccessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());

  // 注入midjourneyAPI
  // const midJourneyKey = req.headers.get("token")
  //   ? req.headers.get("token")
  //   : serverConfig.midJourneyKey;
  // console.log(">>> 注入midjourneyAPI: ", midJourneyKey);

  if (serverConfig.needCode && !serverConfig.mjCodes.has(hashedCode) && !midJourneyKey) {
    return {
      error: true,
      msg: "访问密码不正确或为空，请前往[设置](/#/settings)页输入正确的 MidJourney 访问密码，或者填入你自己的 [Midjourney API Token](https://midjourneyapi.zxx.im/)。",
    };
  }
  // if user does not provide an api key, inject system api key
  if (!midJourneyKey) {
    const midJourneyKey = serverConfig.midJourneyKey;
    if (midJourneyKey) {
      console.log("[Auth] use system mj key");
      req.headers.set("token", midJourneyKey);
    } else {
      console.log("[Auth] admin did not provide an mj key");
    }
  } else {
    console.log("[Auth] use user mj key");
  }

  // if (midJourneyKey) {
  //   req.headers.set("token", midJourneyKey);
  // } else {
  //   return {
  //     error: true,
  //     msg: "Empty Midjourney Api Key. Go to: [MidjourneyAPI](https://midjourneyapi.zxx.im/)",
  //   };
  // }

  return {
    error: false,
  };
}
