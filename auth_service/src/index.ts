import express, { Request, Response, json } from 'express'
import cors from 'cors'
const server = express();

server.use(json())
server.use(cors())

const users: { [key: string  | number ]: any } = {
  "747": {
      "id": 747,
      "name": "Valentina",
      "lastName": "Restrepo"
  },
  "7180": {
      "id": 7180,
      "name": "Angel",
      "lastName": "Góez Giraldo"
  }
}

server.get('/api', (req: Request, res: Response) => {
  res.send(users)
})

server.get('/api/:id', (req: Request, res: Response) => {
  res.send(users[req.params.id])
})

server.listen(8080, () => {
  console.log('App is up and running', 80)
})