cle# permit2-relayer-example

Ejemplo completo para: firmar Permit2 (varios tokens), guardar firmas, y que el relayer aplique permit() + transferFrom() para mover fondos, swap a USDC y repartir.

## Requisitos
- Node.js 16+ instalado
- MetaMask u otra wallet para firmar desde el frontend

## Paso a paso (local)
1. Clona o crea las carpetas `frontend` y `backend` con los archivos proporcionados.
2. En `backend` copia `.env.example` a `.env` y rellena:
   - `RPC_URL` (usa Mumbai para pruebas)
   - `RELAYER_PRIVATE_KEY` (clave privada del relayer con algo de MATIC para gas en testnet)
   - `RECIPIENTS` (direcciones separadas por comas)
3. `cd backend` && `npm install`
4. `npm start` para arrancar el backend (por defecto puerto 3000)
5. Abre `frontend/index.html` en el navegador (o sirve con `npx serve frontend` para evitar problemas CORS)
6. Pulsa el botón — MetaMask pedirá firmas para cada token en `TOKEN_LIST`.
7. Una vez firmado, las firmas quedan guardadas en `backend/signatures.txt`.
8. Para procesar y ejecutar swaps: llama al endpoint `/sweep` con `{ owner: '<direccion del usuario>' }` (puede ser desde Postman o curl). El relayer aplicará las firmas y hará el proceso.

## Notas de seguridad
- Prueba en Mumbai primero. Revisa límites de gas y permisos.
- No subas claves privadas a repos públicos.
- Ajusta slippage (`slippageBps`) en `server.js` según tu tolerancia.
