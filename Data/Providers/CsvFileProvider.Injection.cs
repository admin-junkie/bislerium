﻿namespace BisleriumCafe.Data.Providers;

internal static class CSVFileProviderInjection
{
    public static IServiceCollection AddCsvFileProvider(this IServiceCollection services)
    {
        return services.AddSingleton<FileProvider<User>, CsvFileProvider<User>>()
            .AddSingleton<FileProvider<Spare>, CsvFileProvider<Spare>>()
            .AddSingleton<FileProvider<ActivityLog>, CsvFileProvider<ActivityLog>>()
            .AddSingleton<FileProvider<Membership>, CsvFileProvider<Membership>>()
			.AddSingleton<FileProvider<NewTransaction>, CsvFileProvider<NewTransaction>>();
	}
}
