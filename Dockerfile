FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 5001

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["src/MyIdentityServer.csproj", "src/"]
RUN dotnet restore "src/MyIdentityServer.csproj"
COPY . .
WORKDIR "/src/src"
RUN dotnet build "MyIdentityServer.csproj" -c Release -o /app/build

FROM build AS publish
WORKDIR "/src/src"
RUN dotnet publish "MyIdentityServer.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MyIdentityServer.dll"]