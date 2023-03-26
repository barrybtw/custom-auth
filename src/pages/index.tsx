import { type NextPage } from "next";
import { useForm, type SubmitHandler } from "react-hook-form";
import Head from "next/head";
import { zodResolver } from "@hookform/resolvers/zod";
import { api } from "@/utils/api";
import { z } from "zod";

const schema = z
  .object({
    email: z.string().email(),
    password: z
      .string()
      .min(8, { message: "Password must be at least 8 characters" }),
  })
  .required();

const Home: NextPage = () => {
  const { mutateAsync: signup } = api.auth.signup.useMutation();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (data: any) => {
    console.log(data);

    const loginattempt = await signup({
      email: data.email,
      password: data.password,
    });
    console.log(loginattempt);
  };

  return (
    <>
      <Head>
        <title>Custom Authentication</title>
        <meta name="description" content="Generated by create-t3-app" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <main className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-[#2e026d] to-[#15162c]">
        <form
          onSubmit={handleSubmit(onSubmit)}
          className="flex max-w-2xl flex-col gap-4 text-white"
        >
          <label htmlFor="email">Email</label>
          <input {...register("email")} className="text-black" />
          <label htmlFor="password">Password</label>
          <input {...register("password")} className="text-black" />
          <button type="submit">Signup</button>
        </form>
      </main>
    </>
  );
};

export default Home;
