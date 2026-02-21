/*
 * Copyright 2021 WPPConnect Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { NextFunction, Request, Response } from 'express';

import { clientsArray } from '../util/sessionUtil';

function formatSession(session: string) {
  return session.split(':')[0];
}

const verifyToken = (req: Request, res: Response, next: NextFunction): any => {
  const secureToken = req.serverOptions.secretKey;
  const { session } = req.params;
  const { authorization: token } = req.headers;

  if (!session)
    return res.status(401).send({ message: 'Session not informed' });

  // Custom simplified auth for Render Free Tier (ephemeral storage)
  // Instead of using bcrypt and local JSON salt files, we just check if
  // the Bearer token matches the secretKey directly.
  let isAuthorized = false;

  if (token && typeof token === 'string') {
    const rawToken = token.replace('Bearer ', '').trim();
    if (rawToken === secureToken) {
      isAuthorized = true;
    } else if (rawToken.includes(secureToken)) {
      isAuthorized = true;
    }
  }

  // Fallback for query parameter just in case
  if (!isAuthorized && req.query.token === secureToken) {
    isAuthorized = true;
  }

  if (isAuthorized) {
    req.session = formatSession(req.params.session);
    req.token = secureToken; // Lie about the token to keep TS happy
    req.client = clientsArray[req.session];
    next();
  } else {
    req.logger.error(`Unauthorized access attempt to session ${session} with token ${token}. Expected: ${secureToken}`);
    return res
      .status(401)
      .json({ error: 'Check that the Session and Token are correct' });
  }
};

export default verifyToken;
