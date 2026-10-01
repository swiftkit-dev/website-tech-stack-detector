FROM apify/actor-node-playwright-chrome:22
COPY --chown=myuser package*.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --chown=myuser . ./
CMD ["npm", "start", "--silent"]
