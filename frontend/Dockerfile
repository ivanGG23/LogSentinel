FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# La URL de la API se graba al compilar: debe venir como variable de build
ARG VITE_API_URL
RUN test -n "$VITE_API_URL" || (echo "Falta VITE_API_URL" && exit 1)
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.27-alpine
# Railway define PORT en ejecución; 8080 es el valor por defecto local
ENV PORT=8080
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
