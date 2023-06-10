FROM node:16
WORKDIR /app
COPY ./package.json ./
RUN npm install
COPY . ./
EXPOSE 80
CMD [ "npm","start" ]
# Etapa de construcción
#FROM node:14 as builder
#WORKDIR /app
#COPY package*.json ./
#RUN npm install
#COPY ./src ./src
# Etapa de producción
#FROM node:14-alpine
#WORKDIR /app
#COPY --from=builder /app .
#CMD ["npm", "start"]
