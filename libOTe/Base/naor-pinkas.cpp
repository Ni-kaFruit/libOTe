#include "naor-pinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/DefaultCurve.h"

#define PARALLEL

#ifdef ENABLE_NP

#include <memory>

namespace osuCrypto
{
    //static const  u64 minMsgPerThread(16);

    NaorPinkas::NaorPinkas()
    {

    }


    NaorPinkas::~NaorPinkas()
    {

    }


    void NaorPinkas::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& socket,
        u64 numThreads)
    {
        using namespace DefaultCurve;
        Curve curve;
        std::cout << "naor recv" << "1" << std::endl;
        // should generalize to 1 out of N by changing this. But isn't tested...
        const auto nSndVals(2);
        const auto pointSize = Point::size;
std::cout << "naor recv" << "2" << std::endl;
        std::vector<std::thread> thrds(numThreads);
        std::vector<u8> sendBuff(messages.size() * pointSize);
        std::atomic<u32> remainingPK0s((u32)numThreads);
std::cout << "naor recv" << "3" << std::endl;
        std::vector<u8> cBuff(nSndVals * pointSize);
        auto cRecvFuture = socket.asyncRecv(cBuff.data(), cBuff.size()).share();
        block R;
std::cout << "naor recv" << "4" << std::endl;
        std::array<u8, RandomOracle::HashSize> comm, comm2;
        auto commFuture = socket.asyncRecv(comm);
        auto RFuture = socket.asyncRecv(R).share();
std::cout << "naor recv" << "5" << std::endl;
        for (u64 t = 0; t < numThreads; ++t)
        {
            auto seed = prng.get<block>();

            thrds[t] = std::thread(
                [t, numThreads, &messages, seed, pointSize,
                &sendBuff, &choices, cRecvFuture, &cBuff,
                &remainingPK0s, &socket, nSndVals,&RFuture,&R]()
            {

                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                PRNG prng(seed);

                Curve curve;

                std::vector<Number> pK;
                std::vector<Point>
                    PK_sigma,
                    pC;

                pK.reserve(mEnd - mStart);
                PK_sigma.reserve(mEnd - mStart);
                pC.reserve(nSndVals);

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // get a random value from Z_p
                    pK.emplace_back(prng);

                    // compute
                    //
                    //      PK_sigma[i] = g ^ pK[i]
                    //
                    // where pK[i] is just a random number in Z_p
                    PK_sigma.emplace_back(Point::mulGenerator(pK[j]));
                }

                cRecvFuture.get();
                for (auto u = 0; u < nSndVals; u++)
                {
                    pC.emplace_back();
                    pC[u].fromBytes(&cBuff[pointSize * u]);
                }

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    u8 choice = choices[i];
                    Point PK0 = std::move(PK_sigma[j]);
                    if (choice != 0) {
                        PK0 = pC[choice] - PK0;
                    }

                    PK0.toBytes(&sendBuff[pointSize * i]);
                }

                if (--remainingPK0s == 0)
                    socket.asyncSend(std::move(sendBuff));

                RandomOracle ro(sizeof(block));

                RFuture.get();

                for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
                {
                    // now compute g ^(a * k) = (g^a)^k
                    Point gka = pC[0] * pK[j];

                    auto nounce = i * nSndVals + choices[i];
                    ro.Reset();
                    ro.Update((u8*)&nounce, sizeof(nounce));
                    ro.Update(gka);
                    ro.Update(R);
                    ro.Final(messages[i]);
                }
            });
        }
std::cout << "naor recv" << "6" << std::endl;
        for (auto& thrd : thrds)
            thrd.join();
std::cout << "naor recv" << "7" << std::endl;
        commFuture.get();
        RandomOracle ro;
        ro.Update(R);
        ro.Final(comm2);
        if (comm != comm2)
            throw std::runtime_error("bad commitment " LOCATION);
std::cout << "naor recv" << "8" << std::endl;
    }


    void NaorPinkas::send(
        span<std::array<block, 2>> messages,
        PRNG & prng,
        Channel& socket,
        u64 numThreads)
    {
        using namespace DefaultCurve;
        Curve curve;
std::cout << "naor send" << "1" << std::endl;
        block R = prng.get<block>();
        // one out of nSndVals OT.
        u64 nSndVals(2);
        std::vector<std::thread> thrds(numThreads);
        //auto seed = prng.get<block>();
std::cout << "naor send" << "2" << std::endl;
        Number alpha(prng);
        const auto pointSize = Point::size;
        std::vector<Point> pC;
        pC.reserve(nSndVals);
std::cout << "naor send" << "3" << std::endl;
        pC.emplace_back(Point::mulGenerator(alpha));
std::cout << "naor send" << "4" << std::endl;
        std::vector<u8> sendBuff(nSndVals * pointSize);
        pC[0].toBytes(sendBuff.data());
std::cout << "naor send" << "5" << std::endl;
        for (u64 u = 1; u < nSndVals; u++)
        {
            // TODO: Faster to use hash to curve to randomize?
            pC.emplace_back(Point::mulGenerator(Number(prng)));
            pC[u].toBytes(&sendBuff[pointSize * u]);
        }
std::cout << "naor send" << "6" << std::endl;
        socket.asyncSend(std::move(sendBuff));
std::cout << "naor send" << "7" << std::endl;
        // sends a commitment to R. This strengthens the security of NP01 to
        // make the protocol output uniform strings no matter what.
        RandomOracle ro;
        std::vector<u8> comm(RandomOracle::HashSize);
        ro.Update(R);
        ro.Final(comm.data());
        socket.asyncSend(std::move(comm));
std::cout << "naor send" << "8" << std::endl;

        for (u64 u = 1; u < nSndVals; u++)
            pC[u] *= alpha;
std::cout << "naor send" << "9" << std::endl;
        std::vector<u8> buff(pointSize * messages.size());
        auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();
std::cout << "naor send" << "10" << std::endl;
        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([
                t, pointSize, &messages, recvFuture,
                    numThreads, &buff, &alpha, nSndVals, &pC,&socket,&R]()
            {
                Curve curve;
                Point pPK0;

                RandomOracle ro(sizeof(block));
                recvFuture.get();

                if (t == 0)
                    socket.asyncSendCopy(R);


                auto mStart = t * messages.size() / numThreads;
                auto mEnd = (t + 1) * messages.size() / numThreads;

                for (u64 i = mStart; i < mEnd; i++)
                {

                    pPK0.fromBytes(&buff[pointSize * i]);
                    pPK0 *= alpha;


                    auto nounce = i * nSndVals;
                    ro.Reset();
                    ro.Update((u8*)&nounce, sizeof(nounce));
                    ro.Update(pPK0);
                    ro.Update(R);
                    ro.Final(messages[i][0]);

                    for (u64 u = 1; u < nSndVals; u++)
                    {
                        Point fetmp = pC[u] - pPK0;

                        ++nounce;
                        ro.Reset();
                        ro.Update((u8*)&nounce, sizeof(nounce));
                        ro.Update(fetmp);
                        ro.Update(R);
                        ro.Final(messages[i][u]);
                    }
                }
            });
        }
std::cout << "naor send" << "11" << std::endl;
        for (auto& thrd : thrds)
            thrd.join();
    }
}

#endif
