import prismaClient from "../../prisma";
import { compare } from "bcryptjs";
import { sign } from "jsonwebtoken";

interface AuthRequest {
  email: string,
  password: string,
}

class AuthUserService {

  async execute({ email, password }: AuthRequest){

    // Verifica se usuario existe
    const user = await prismaClient.user.findFirst({
      where: {
        email: email
      }
    })

    if(!user){
      throw new Error("Usuario/Senha incorreta")
    }

    const passwordCompare = await compare(password, user.password)

    if(!passwordCompare){
      throw new Error("Usuario/Senha incorreta")
    }

    // Gerar token JWT e retornar dados do usuario
    const token = sign(
      {
        name: user.name,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        subject: user.id,
        expiresIn: '30d'
      }
    )

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      token: token
    }


  }

}

export { AuthUserService }